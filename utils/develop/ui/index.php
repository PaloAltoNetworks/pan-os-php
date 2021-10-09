<!DOCTYPE html>
<html>

<head>
    <title>PAN-OS-PHP UI</title>
    <link rel="stylesheet" href=
            "https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css"
          integrity=
                  "sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh"
          crossorigin="anonymous">


    <!--<script src=
                    "https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js">
    </script>
    <script type="text/javascript" src="jquery-3.5.1.min.js"></script>
    -->

    <script src=
                    "https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js">
    </script>

    <script type="text/javascript" src="json_array.js"></script>

    <script src=
                    "https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js">
    </script>
    <script src=
                    "https://maxcdn.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js">
    </script>


    <script>

        var server_url = window.location.protocol + "//" + window.location.host;

        $(document).ready(function () {

            // Denotes total number of rows
            var rowIdx = 0;

            // jQuery button click event to add a row
            $('#storeBtn').on('click', function () {

/*
                $("table > tbody > tr").each(function ()
                {
                    var currentRow = $(this); //Do not search the whole HTML tree twice, use a subtree instead
                    var id = currentRow.attr('id');
                    id = id.substr(1);

                    var SCRIPT = currentRow.find("#script"+id).val();
                    var ACTION = currentRow.find("#action"+id).val();
                    var ACTION_input = currentRow.find("#action-input"+id).val();

                    var FILTER = currentRow.find("#filter"+id).val();
                    var FILTER_input = currentRow.find("#filter-input"+id).val();

                    var ADDITION = currentRow.find("#additionalArg-input"+id).val();

                    console.log( SCRIPT + " " + ACTION + " " + ACTION_input + " " + FILTER + " " + FILTER_input + " " + ADDITION );

                });
                */
                var i = 1;
                for( i; i <= rowIdx; i++ )
                {
                    console.log( $( "#command" + i ).val() );
                    console.log( $( "#commandapi" + i ).val() );
                }

            });

            $( "#json-store" ).submit(function( event ) {

                console.log( $( "#json-store" ).serialize() );
            });

            // jQuery button click event to add a row
            $('#addBtn').on('click', function () {

                var Idx = ++rowIdx;
                // Adding a row inside the tbody.
                $('#tbody').append(`<tr id="R${Idx}">

                    <td class="text-center">
                        <button class="btn btn-danger remove"
                        type="button">Remove</button>
                    </td>
                    <td class="row-index text-center">
                        <select name="script${Idx}" id="script${Idx}" style="width:100%">
                            <option value="---" selected="selected">Select script</option>
                        </select>
                    </td>
                    <td class="row-index text-center">
                        <select name="action${Idx}" id="action${Idx}" style="width:100%">
                            <option value="---" selected="selected">Select action</option>
                        </select>
                        <input type="text" disabled style="width:100%"
                                id="action-input${Idx}" name="action-input${Idx}"
                        >
                        </br>
                        <p type="text" disabled style="width:100%"
                            id="action-desc${Idx}" name="action-desc${Idx}"
                        >no description
                        </p>
                    </td>
                    <td class="row-index text-center">
                        <select name="filter${Idx}" id="filter${Idx}" style="width:100%">
                            <option value="---" selected="selected">Select filter</option>
                        </select>
                        <select name="filter-operator${Idx}" id="filter-operator${Idx}" style="width:100%">
                            <option value="---" selected="selected">Select operator</option>
                        </select>
                        <input type="text" disabled style="width:100%"
                            id="filter-input${Idx}" name="filter-input${Idx}"
                        >
                        </br>
                        <p type="text" disabled style="width:100%"
                            id="filter-desc${Idx}" name="filter-desc${Idx}"
                        >no description
                        </p>
                    </td>
                </tr>
                <tr id="R${Idx}">
                    <td>
                    shadow-json
                    <input type="checkbox" id="shadowjson${Idx}" name="shadowjson${Idx}"
                    checked
                    >
                </td>
                <td>
                    location
                    <input type="text" id="location${Idx}" name="location${Idx}" value="any" />
                </td>
                </tr>
                <tr id="R${Idx}">
                    <td colspan="1"><button onclick="copyTextButton( ${Idx} )">Copy command</button></td>
                    <td colspan="3">
                        <input type="text" disabled style="width:100%"
                            id="command${Idx}" name="command${Idx}"
                        >
                    </td>

                </tr>
                <tr id="R${Idx}">
                    <td colspan="1">
                        <button onclick="runButton( ${Idx} )">RUN single command</button>
                    </td>
                    <td colspan="3">
                        <input type="text" disabled style="width:100%"
                            id="commandapi${Idx}" name="commandapi${Idx}"
                        >
                    </td>

                </tr>
                `);




                var selectedScript = "";
                var selectedFilter = "";
                ScriptID = $( "#script" + Idx );

                ActionID = $( "#action" + Idx );
                ActionInputID = $("#action-input" + Idx);
                ActionDescriptionID = $("#action-desc" + Idx);

                FilterID = $( "#filter" + Idx );
                FilterOperatorID = $("#filter-operator" + Idx);
                FilterInputID = $("#filter-input" + Idx);
                FilterDescriptionID = $("#filter-desc" + Idx);

                $( "#script" + Idx ).append(produceOptionsScript(subjectObject))
                    .change(function(){
                    selectedScript = $(this).children("option:selected").val();
                    <!--alert("You have selected the script - " + selectedScript);-->
                    console.log( 'SCRIPT:|'+selectedScript+'|'); // this will show the info it in firebug console

                    $( "#action" + Idx )
                        .find('option')
                        .remove()
                        .end()
                        .append( '<option value="---" selected="selected">Select action</option>' );

                    $("#action-desc" + Idx).text( "no description");
                    $("#action-input" + Idx).prop( "disabled", true)
                        .val( "");

                    $( "#filter" + Idx )
                        .find('option')
                        .remove()
                        .end()
                        .append( '<option value="---" selected="selected">Select filter</option>' );

                    $("#filter-operator" + Idx)
                        .find('option')
                        .remove()
                        .end()
                        .append( '<option value="---" selected="selected">Select operator</option>' );

                    $("#filter-input" + Idx).prop( "disabled", true)
                        .val( "");

                    $("#filter-desc" + Idx).text( "no description");


                    if( selectedScript == '---' )
                    {}
                    else
                    {
                        $( "#action" + Idx )
                            .append(produceOptionsActionFilter( selectedScript, 'action' ))
                            .val('---');


                        $( "#filter" + Idx )
                            .append(produceOptionsActionFilter( selectedScript, 'filter' ))
                            .val('---');
                    }

                    updateScriptsyntax( Idx );
                });

                $( "#action" + Idx ).change(function(){
                    selectedAction = $(this).children("option:selected").val();
                    console.log( 'ACTION:|'+selectedAction+'|'); // this will show the info it in firebug console

                    $("#action-desc" + Idx).text( "no description");
                    $("#action-input" + Idx).prop( "disabled", true);

                    if( selectedAction == '---' )
                    {}
                    else
                    {
                        var action = subjectObject[selectedScript]['action'][selectedAction];

                        if( "args" in action )
                        {
                            var args = action['args'];
                            console.log( "ARGS: "+JSON.stringify( args ) );
                            $("#action-desc" + Idx).text( JSON.stringify( args ) );


                            $("#action-input" + Idx).prop( "disabled", false);

                        }

                    }

                    updateScriptsyntax( Idx );
                });

                $( "#action-input" + Idx ).change(function(){
                    updateScriptsyntax( Idx );
                });
                $("#filter" + Idx).change(function(){
                    selectedFilter = $(this).children("option:selected").val();
                    console.log( 'FILTER:|'+selectedFilter+'|'); // this will show the info it in firebug console

                    $("#filter-operator" + Idx)
                        .find('option')
                        .remove()
                        .end()
                        .append( '<option value="---" selected="selected">Select operator</option>' );

                    $("#filter-input" + Idx).prop( "disabled", true)
                        .val( "");

                    $("#filter-desc" + Idx).text( "no description");

                    if( selectedFilter == '---' )
                    {}
                    else
                    {
                        $("#filter-operator" + Idx)
                            .append(produceOptionsFilterOperator( selectedScript, selectedFilter))
                            .val('---');
                    }

                    updateScriptsyntax( Idx );
                });

                $("#filter-operator" + Idx).change(function(){
                    var selectedFilterOperator = $(this).children("option:selected").val();
                    console.log( 'FILTER-operator:|'+selectedFilterOperator+'|'); // this will show the info it in firebug console


                    $("#filter-desc" + Idx).text( "no description");

                    if( selectedFilter == '---' )
                    {}
                    else
                    {
                        var operator = subjectObject[selectedScript]['filter'][selectedFilter]['operators'][selectedFilterOperator];
                        var arg = operator['arg'];
                        console.log( "ARG: "+arg );

                        if( arg )
                        {
                            console.log( "ARG2: "+arg );
                            $("#filter-input" + Idx).prop( "disabled", false);

                        }
                        else
                        {
                            $("#filter-input" + Idx).prop( "disabled", true)
                                .val( "");
                        }

                        if( "help" in operator )
                        {
                            var help = operator['help'];
                            console.log( "HELP: "+help );
                            $("#filter-desc" + Idx).text( help);
                        }
                    }

                    updateScriptsyntax( Idx );
                });

                $( "#filter-input" + Idx ).change(function(){
                    updateScriptsyntax( Idx );
                });


                $("#shadowjson" + Idx ).change( function()
                {
                    updateScriptsyntax( Idx );
                });

                $( "#location" + Idx ).change(function(){
                    updateScriptsyntax( Idx );
                });
            });

            // jQuery button click event to remove a row.
            $('#tbody').on('click', '.remove', function () {

                // Getting all the rows next to the row
                // containing the clicked button
                var child = $(this).closest('tr').nextAll();

                // Iterating across all the rows
                // obtained to change the index
                child.each(function () {

                    // Getting <tr> id.
                    var id = $(this).attr('id');

                    // Getting the <p> inside the .row-index class.
                    var idx = $(this).children('.row-index').children('p');

                    // Gets the row number from <tr> id.
                    var dig = parseInt(id.substring(1));

                    // Modifying row index.
                    idx.html(`Row ${dig - 1}`);

                    // Modifying row id.
                    $(this).attr('id', `R${dig - 1}`);
                });

                // Removing the current row.
                $(this).closest('tr').next().remove();
                $(this).closest('tr').next().remove();
                $(this).closest('tr').next().remove();
                $(this).closest('tr').remove();




                // Decreasing total number of rows by 1.
                //rowIdx--;
            });

        });

        function produceOptions(programming_languages) {
            var populated_options = "";
            sortKeys(programming_languages);
            $.each(programming_languages, function (key, value){
                var object = value;
                $.each(object, function(k,v) {
                    populated_options += "<option value='"+k+"'>"+v+"</option>";
                })
            });

            return populated_options;
        }

        function produceOptionsScript(programming_languages) {
            var populated_options = "";
            sortKeys(programming_languages);

            $.each(programming_languages, function (key, value){
                var object = key;
                populated_options += "<option value='"+key+"'>"+key+"</option>";
            });

            return populated_options;
        }

        function produceOptionsActionFilter(programming_languages, type) {
            var populated_options = "";

            programming_languages = subjectObject[programming_languages][type]
            sortKeys(programming_languages);

            $.each(programming_languages, function (key, value){
                var object = key;
                populated_options += "<option value='"+key+"'>"+key+"</option>";
            });

            return populated_options;
        }

        function produceOptionsFilterOperator(script, filter) {
            var populated_options = "";

            programming_languages = subjectObject[script]['filter'][filter]['operators']
            sortKeys(programming_languages);

            $.each(programming_languages, function (key, value){
                var object = key;

                if (key.indexOf(",") !== false )
                {
                    //not working well; Todo: combination could be possible needed, how to do
                    var result=key.split(',');
                    $.each(result, function (key, value) {
                        var object = key;
                        populated_options += "<option value='" + result + "'>" + value + "</option>";
                    });
                }
                else
                    populated_options += "<option value='"+key+"'>"+key+"</option>";

            });

            return populated_options;
        }

        function updateScriptsyntax( Idx ) {

            var SCRIPT = $( "#script" + Idx ).children("option:selected").val();

            var ACTION = $( "#action" + Idx ).children("option:selected").val();
            var ACTIONinput = $( "#action-input" + Idx ).val();

            var Actiontext = "";
            var Actiontextapi = "";
            if( ACTION !== "---" )
            {
                if( ACTIONinput !== "" )
                    ACTIONinput = ":"+ACTIONinput;

                Actiontext = " 'actions=" +ACTION +ACTIONinput+ "'";
                Actiontextapi = "&actions=" +ACTION +ACTIONinput;
            }

            var FILTER = $( "#filter" + Idx ).children("option:selected").val();
            var FILTERoperator = $( "#filter-operator" + Idx ).children("option:selected").val();
            var FILTERinput = $( "#filter-input" + Idx ).val();

            var Filtertext = "";
            var Filtertextapi = "";
            if( FILTER !== "---" && FILTERoperator !== "---" )
            {
                Filtertext = " 'filter=(  (" +FILTER+ " " + FILTERoperator + " " + FILTERinput + ")  )'";
                Filtertextapi = "&filter=((" +FILTER+ "%20" + FILTERoperator + "%20" + FILTERinput + "))";
            }

            var message = "pa_" +SCRIPT+ "-edit";
            message += Actiontext;
            message += Filtertext;


            //var checkedValue = document.getElementById('shadowjson').checked;
            var checkedValue = $( "#shadowjson" + Idx ).is(':checked');
            if( checkedValue )
                message += " shadow-json";

            //var locationValue = document.getElementById('location').value;
            var locationValue = $( "#location" + Idx ).val();
            if( locationValue !== "---" )
            {
                message += " location=";
                message += locationValue;
            }

            var e = document.getElementById("configSelect");
            var dropdownselection = e.options[e.selectedIndex].text;
            console.log( "DropDown: "+dropdownselection );

            if( dropdownselection !== "---" )
            {
                message += " in=";
                message += dropdownselection;
            }

            console.log( message );
            $("#command" + Idx).val( message );


            var message2 = server_url + "/utils/develop/api/v1/tool.php/" +SCRIPT+ "?";
            message2 += Actiontextapi;
            message2 += Filtertextapi;

            if( checkedValue )
                message2 += "&shadow-json";

            if( locationValue !== "---" )
            {
                message2 += "&location=";
                message2 += locationValue;
            }

            if( dropdownselection !== "---" )
            {
                message2 += "&in=";
                message2 += dropdownselection;
            }

            console.log( message2 );

            $("#commandapi" + Idx).val( message2 );

            //document.getElementById("user_form").action = message2;
            document.user_form.action = message2;
        }

        function sortKeys(obj_1) {
            var key = Object.keys(obj_1)
                .sort(function order(key1, key2) {
                    if (key1 < key2) return -1;
                    else if (key1 > key2) return +1;
                    else return 0;
                });

            // Taking the object in 'temp' object
            // and deleting the original object.
            var temp = {};

            for (var i = 0; i < key.length; i++) {
                temp[key[i]] = obj_1[key[i]];
                delete obj_1[key[i]];
            }

            // Copying the object from 'temp' to
            // 'original object'.
            for (var i = 0; i < key.length; i++) {
                obj_1[key[i]] = temp[key[i]];
            }
            return obj_1;
        }

        function copyTextButton( Idx)
        {

            string = $( "#command" + Idx ).val();

            const el = document.createElement('textarea');
            el.value = string;
            document.body.appendChild(el);
            el.select();
            document.execCommand('copy');
            document.body.removeChild(el);
        }
        function runButton( Idx)
        {
            //document.getElementById("user_form").submit();
        }

        function uploadButton( )
        {
            var message = server_url + "/utils/develop/api/v1/file_upload.php"
            document.getElementById("user_form").action = message;
            document.getElementById("user_form").submit();
        }

    </script>

</head>

<body>


<div style="border:0px solid #000000; padding: 10px; width:100%">

    <div class="load-json" style="border:1px solid #000000; padding: 10px; width:100%">
        <table class="table table-bordered" style="width:100%">
            <tr>
                <td style="width:50%" >
                    load Playbook from JSON-file:
                    <input type="file" id="json-input" name="json-input" >
                </td>
                <td>
                    store Playbook to JSON-file:
                    <input type="text" id="json-output" />
                    <button class="btn btn-md btn-primary" id="storeBtn" type="button">Store JSON </button>
                </td>
            </tr>
        </table>
    </div>

    <form id="user_form" target="_blank" name="user_form" method="post" enctype="multipart/form-data">

    <div class="input-output" style="border:1px solid black; padding: 10px;">
        <table class="table table-bordered" style="width:100%">
            <tr>
                <td style="width:50%" >
                    INPUT-config:<br/>
                    <input type="file" id="configInput" name="configInput" >
                    <button onclick="uploadButton( )" id="uploadBtn" type="button">Upload</button>
                </td>
                <td style="width:50%" >
                    select Project file:
                    <select id="configSelect" name="configSelect" class="form-control input-sm">
                        <option value="---" selected>---</option>
                        <?php
                        foreach(glob(dirname(__FILE__) . '/../api/v1/project/*') as $filename)
                        {
                            $filename = basename($filename);
                            echo "<option value='" . $filename . "'>".$filename. "</option>";
                        }
                        ?>
                    </select>
                </td>
            </tr>
        </table>
    </div>

    <div class="table-responsive" style="border:1px solid black; padding: 10px; width:100%">
        <table class="table table-bordered" style="width:100%">
            <thead>
            <tr>
                <th class="text-center">Remove Row</th>
                <th class="text-center">SCRIPT</th>
                <th class="text-center">ACTION</th>
                <th class="text-center">FILTER</th>
            </tr>
            </thead>
            <form id="json-store">
            <tbody id="tbody">

            </tbody>
            </form>
        </table>
        <button class="btn btn-md btn-primary"
                id="addBtn" type="button">
            Add new Row
        </button>
    </div>
    </form>


</div>

missing stuff:</br>
1) add additional action</br>
2) add additional filter, with and / or</br>
3) rule filter operator has.from.query subquery1 -> add this automatically and define based on filter src/dst/srv what subquery can be done and prefill the part there</br>
4) additional arguments like location=vsys1 and shadow-xyz</br>
5) migration part with vendor select</br>

6) user login [create first default project]</br>
7) project creation</br>
8) upload config</br>
9) display uploaded config -</br>
10) after running - possible to download: 1) log 2) XML file 3) JSON 4) full bundle</br>

</body>

</html>