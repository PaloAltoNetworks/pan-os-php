<?php
session_start();
include "test/db_conn.php";
if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
{
    $panconfkeystoreFILE = $_SESSION['folder']."/.panconfkeystore";
    $projectFOLDER = $_SESSION['folder'].'/*';
}
else
{
    $tmpFOLDER = '/../../api/v1/project';
    $panconfkeystoreFILE = dirname(__FILE__) . $tmpFOLDER.'/.panconfkeystore';
    $projectFOLDER = dirname(__FILE__) . $tmpFOLDER.'/*';
}


?>
<!--
/**
 * ISC License
 *
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
-->

<!DOCTYPE html>
<html>

<head>
    <title>PAN-OS-PHP UI</title>

    <link rel="stylesheet"
          href="../../common/html/bootstrap.min.css"
          crossorigin="anonymous"
    >
    <script type="text/javascript"
            src="../../common/html/jquery.min.js"
    ></script>

    <script type="text/javascript"
            src="../../common/html/bootstrap.min.js"
    ></script>



    <script type="text/javascript"
            src="json_array.js"
    ></script>


    <script type="text/javascript"
            src="ui_function.js"
    ></script>

    <script type="text/javascript"
            src="js.js"
    ></script>

</head>

<body>


<div style="border:0px solid #000000; padding: 10px; width:100%">

    <div class="menu" style="border:1px solid black; padding: 10px;">
        <table class="table table-bordered" style="width:100%">
            <tr>
            <tr>
                <td><a href="index.php">MAIN page</a></td>
                <td><a href="single.php">single command</a></td>
                <td><a href="playbook.php">JSON PLAYBOOK</a></td>
                <td><a href="preparation.php">upload file / store APIkey</a></td>
                <?php
                if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
                {
                    echo '<td>logged in as: '.$_SESSION['name'].'  |  <a href="test/logout.php">LOGOUT</a></td>';
                }
                ?>

            </tr>
        </table>
    </div>

    <form id="user_form" target="_blank" name="user_form" method="post" enctype="multipart/form-data">

        <div class="input-output" style="border:1px solid black; padding: 10px;">
            <table class="table table-bordered" style="width:100%">
                <tr>
                    <td style="width:50%" >
                        <b>offline MODE:</b>
                        <br/><br/>
                        INPUT-config:<br/>
                        <input type="file" id="configInput" name="configInput" />
                        <br/>
                        <button onclick="uploadButton( )" id="uploadBtn" type="button">Upload File</button>
                    </td>
                    <td style="width:50%" >
                        check available Project file(s):
                        <select id="configSelect" name="configSelect" class="form-control input-sm">
                            <option value="---" selected>---</option>
                            <?php
                            foreach( glob($projectFOLDER) as $filename )
                            {
                                $filename = basename($filename);

                                if( $filename == "html" )
                                    continue;

                                echo "<option value='" . $filename . "'>".$filename. "</option>";
                            }
                            ?>
                        </select>
                        //FR: remove file
                    </td>
                </tr>
                <tr>
                    <td style="width:50%" >
                        <b>online MODE:</b>
                        <br/><br/>
                        api://<input type="text" id="configapi" name="configapi" value="192.168.10.1" />
                        <br/>

                        username: <input type="text" id="user" name="user" value="" />
                        password: <input type="text" id="pw" name="pw" value="" />

                        <br/>
                        or<br/>
                        PAN-OS APIkey: <input type="text" id="apikey" name="apikey" value="" />
                        <br/>
                        <input type="text" disabled style="width:100%"
                               id="commandapikey" name="commandapikey"
                        >
                        <br/><br/>
                        <button onclick="createApiKey()" id="createAPIkey" type="button">store APIkey</button>
                    </td>
                    <td style="width:50%" >
                        check available Host IP(s):
                        <select id="configapi" name="configapi" class="form-control input-sm">
                            <option value="---" selected>---</option>
                            <?php
                            foreach( file($panconfkeystoreFILE ) as $entry )
                            {
                                $host = explode( ":", $entry);

                                echo "<option value='" . $host[0] . "'>".$host[0]. "</option>";
                            }
                            ?>
                        </select>
                        //FR: remove entry
                    </td>
                </tr>
            </table>
        </div>

    </form>


</div>