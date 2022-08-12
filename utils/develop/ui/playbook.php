<?php
session_start();
include "test/db_conn.php";
if (isset($_SESSION['username']) && isset($_SESSION['id'])) {

    if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
    {
        $panconfkeystoreFILE = $_SESSION['folder']."/.panconfkeystore";
        $projectFOLDER = $_SESSION['folder'];
    }
    else
    {
        $tmpFOLDER = '/../../api/v1/project';
        $panconfkeystoreFILE = dirname(__FILE__) . $tmpFOLDER.'/.panconfkeystore';
        $projectFOLDER = dirname(__FILE__) . $tmpFOLDER;
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
                <td>logged in as: <?=$_SESSION['name']?>  |  <a href="test/logout.php">LOGOUT</a></td>
            </tr>
        </table>
    </div>

    <div class="load-json" style="border:1px solid #000000; padding: 10px; width:100%">
        <table class="table table-bordered" style="width:100%">
            <tr>
                <td style="width:50%" >
                    load Playbook from JSON-file:

                    <input type="button" value="Clear TextArea" onclick="eraseText();">
                    <form method="post">
                        <textarea disabled id="js-textarea" style="width:100%" ></textarea>
                        <input type="file" id="js-file" accept=".txt,.json" onclick="this.value=null">
                    </form>
                </td>
                <td>
                    store Playbook to JSON-file:
                    <input type="text" id="json-output" value="playbook.json" />
                    <button class="btn btn-md btn-primary" id="storeBtn" type="button">download PLAYBOOK JSON file</button>
                    <div>
                        <textarea type="text" disabled id="json-display-out" name="json-display-out" style="width:100%" ></textarea>
                    </div>
                </td>
            </tr>
        </table>
    </div>

    <form id="user_form" target="_blank" name="user_form" method="post" enctype="multipart/form-data">

        <div class="input-output" style="border:1px solid black; padding: 10px;">
            <table class="table table-bordered" style="width:100%">
                <tr>
                    <a href="preparation.php">go to preparation site:</a>
                    <td style="width:50%" >
                        <b>offline MODE:</b>
                        <input type="radio" id="offlinemode" name="mode" value="offlinemode" checked>
                    </td>
                    <td style="width:50%" >
                        select Project file:
                        <select id="configSelect" name="configSelect" class="form-control input-sm">
                            <option value="---" selected>---</option>
                            <?php
                            foreach( glob($projectFOLDER.'/*') as $filename )
                            {
                                $filename = basename($filename);

                                if( $filename == "html" )
                                    continue;

                                echo "<option value='" . $filename . "'>".$filename. "</option>";
                            }
                            ?>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td style="width:50%" >
                        <b>online MODE:</b>
                        <input type="radio" id="onlinemode" name="mode" value="onlinemode">
                    </td>
                    <td style="width:50%" >
                        select Host for 'api://'
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
                    </td>
                </tr>
            </table>
        </div>


        <div class="table-responsive" style="border:1px solid black; padding: 10px; width:100%">
            <table id="myTable" class="table table-bordered" style="width:100%">
                <thead>
                <tr>
                    <th class="text-center">Remove Row</th>
                    <th class="text-center">SCRIPT</th>
                    <th class="text-center">
                        ACTION


                    </th>
                </tr>
                </thead>
                <form id="json-store">
                    <tbody id="tbody">

                    </tbody>
                </form>
            </table>
            <button class="btn btn-md btn-primary"
                    id="addBtn" type="button">
                new Row
            </button>
        </div>
    </form>


</div>

missing stuff:</br>
1) rule filter 'dst' operator 'has.from.query subquery1' -> add this automatically and define based on filter src/dst/srv what subquery can be done and prefill the part there</br>
2) migration part with vendor select</br>
</br>
3) user login [create first default project]</br>
4) project creation</br>
5) after running - possible to download: 1) log 2) XML file 3) JSON 4) full bundle</br>

ruletype=</br>
devicetype=</br>
securityprofiletype=</br>

</body>

</html>

<?php }else{
	header("Location: test/index.php");
} ?>