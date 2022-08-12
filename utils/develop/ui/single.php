<?php
session_start();
include "test/db_conn.php";
if (isset($_SESSION['username']) && isset($_SESSION['id']))
{
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


    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-giJF6kkoqNQ00vy+HMDP7azOuL0xtbfIcaT9wjKHr8RbDVddVHyTfAAsrekwKmP1" crossorigin="anonymous">

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


<div >


    <div class="border shadow p-3 rounded">
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

    <form id="user_form" target="_blank" name="user_form" method="post" enctype="multipart/form-data" class="border shadow p-3 rounded">

        <div class="border shadow p-3 rounded">
            <table style="width:100%" class="border shadow p-3 rounded">
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
                            foreach( glob( $projectFOLDER.'/*' ) as $filename )
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
                            foreach( file( $panconfkeystoreFILE ) as $entry )
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

        <div class="table-responsive" class="border shadow p-3 rounded">
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
                    id="addBtn" type="button" hidden="hidden">
                new Row
            </button>
        </div>
    </form>


</div>

</body>

</html>

<?php }else{
    header("Location: test/index.php");
} ?>