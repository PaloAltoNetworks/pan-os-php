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
            src="json_array.js"
    ></script>

    <script type="text/javascript"
            src="../../common/html/bootstrap.min.js"
    ></script>

    <!--
        <link rel="stylesheet"
              href="html/bootstrap.min.css"
              crossorigin="anonymous"
        >
        <script type="text/javascript"
                src="html/jquery.min.js"
        ></script>

        <script type="text/javascript"
                src="json_array.js"
        ></script>

        <script type="text/javascript"
                src="html/bootstrap.min.js"
        ></script>
        -->

    <script>

        var server_url = window.location.protocol + "//" + window.location.host;
        var fullpathname = window.location.pathname;
        var pathToReplace = "/utils/develop/ui/";

        var path = fullpathname.replace(pathToReplace, "");
        server_url = server_url + path;

        var subjectObject2 = subjectObject;

        var rowIdx = 0;
        var columnActionIdx = 2;
        var columnFilterIdx = 3;
        var columnIdx = 3;

        $(document).ready(function () {

            // Denotes total number of rows


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
                var ActionIdx = columnActionIdx;
                var FilterIdx = columnFilterIdx;

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
                        <select name="action${Idx}-${ActionIdx}" id="action${Idx}-${ActionIdx}" style="width:100%">
                            <option value="---" selected="selected">Select action</option>
                        </select>
                        <input type="text" disabled style="width:100%"
                                id="action-input${Idx}-${ActionIdx}" name="action-input${Idx}-${ActionIdx}"
                        >
                        </br>
                        <p type="text" disabled style="width:100%"
                            id="action-desc${Idx}-${ActionIdx}" name="action-desc${Idx}-${ActionIdx}"
                        >no description
                        </p>
                    </td>
                    <td class="row-index text-center">
                        <select name="filter${Idx}-${FilterIdx}" id="filter${Idx}-${FilterIdx}" style="width:100%">
                            <option value="---" selected="selected">Select filter</option>
                        </select>
                        <select name="filter-operator${Idx}-${FilterIdx}" id="filter-operator${Idx}-${FilterIdx}" style="width:100%">
                            <option value="---" selected="selected">Select operator</option>
                        </select>
                        <input type="text" disabled style="width:100%"
                            id="filter-input${Idx}-${FilterIdx}" name="filter-input${Idx}-${FilterIdx}"
                        >
                        </br>
                        <p type="text" disabled style="width:100%"
                            id="filter-desc${Idx}-${FilterIdx}" name="filter-desc${Idx}-${FilterIdx}"
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
                    <td></td>
                    <td></td>
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
                var ScriptID = $( "#script" + Idx );

                var ActionID = $( "#action" + Idx+"-"+ActionIdx );
                var ActionInputID = $("#action-input" + Idx+"-"+ActionIdx);
                var ActionDescriptionID = $("#action-desc" + Idx+"-"+ActionIdx);

                var FilterID = $( "#filter" + Idx+"-"+FilterIdx );
                var FilterOperatorID = $("#filter-operator" + Idx+"-"+FilterIdx);
                var FilterInputID = $("#filter-input" + Idx+"-"+FilterIdx);
                var FilterDescriptionID = $("#filter-desc" + Idx+"-"+FilterIdx);

                $( "#script" + Idx ).append(produceOptionsScript(subjectObject))
                    .change(function(){
                        selectedScript = $(this).children("option:selected").val();
                        <!--alert("You have selected the script - " + selectedScript);-->
                        console.log( 'SCRIPT:|'+selectedScript+'|'); // this will show the info it in firebug console


                        for( var i = 2; i <= columnActionIdx; i++ )
                        {
                            $( "#action" + Idx+"-"+i )
                                .find('option')
                                .remove()
                                .end()
                                .append( '<option value="---" selected="selected">Select action</option>' );

                            $("#action-desc" + Idx+"-"+i).text( "no description");
                            $("#action-input" + Idx+"-"+i).prop( "disabled", true)
                                .val( "");
                        }

                        for( var i = 3; i <= columnFilterIdx; i++ )
                        {
                            $( "#filter" + Idx+"-"+i )
                                .find('option')
                                .remove()
                                .end()
                                .append( '<option value="---" selected="selected">Select filter</option>' );

                            $("#filter-operator" + Idx+"-"+i)
                                .find('option')
                                .remove()
                                .end()
                                .append( '<option value="---" selected="selected">Select operator</option>' );

                            $("#filter-input" + Idx+"-"+i).prop( "disabled", true)
                                .val( "");

                            $("#filter-desc" + Idx+"-"+i).text( "no description");
                        }



                        if( selectedScript == '---' )
                        {}
                        else
                        {
                            for( var  i = 2; i <= columnActionIdx; i++ )
                                $( "#action" + Idx+"-"+i )
                                    .append(produceOptionsActionFilter( selectedScript, 'action' ))
                                    .val('---');

                            for( var i = 3; i <= columnFilterIdx; i++ )
                                $( "#filter" + Idx+"-"+i )
                                    .append(produceOptionsActionFilter( selectedScript, 'filter' ))
                                    .val('---');
                        }

                        updateScriptsyntax( Idx );

                        updateActionFiltersyntax( selectedScript, Idx, ActionIdx, FilterIdx);
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

            $("#addBtn").trigger('click');

            $('#addActionBtn').on('click', function() {

                var ActionIdx = ++columnActionIdx;
                var FilterIdx = columnFilterIdx;
                var deleteColumnID = ++columnIdx;

                var rows = $("#myTable").children('tbody').children('tr');

                var selectedScript = $("#script"+rowIdx).children("option:selected").val();

                var testID = 1;
                rows.each(function () {

                    // Getting <tr> id.
                    var id = $(this).attr('id');
                    // Getting the <p> inside the .row-index class.
                    var Idx = $(this).children('.row-index').children('p');
                    // Gets the row number from <tr> id.
                    var dig = parseInt(id.substring(1));


                    if( testID == 1 )
                    {
                        $(this).append( $(
                            `<td id=${deleteColumnID} class="row-index text-center">
                                <select name="action${rowIdx}-${ActionIdx}" id="action${rowIdx}-${ActionIdx}" style="width:100%">
                                    <option value="---" selected="selected">Select action</option>
                                </select>
                                <input type="text" disabled style="width:100%"
                                    id="action-input${rowIdx}-${ActionIdx}" name="action-input${rowIdx}-${ActionIdx}"
                                    >
                                </br>
                                <p type="text" disabled style="width:100%"
                                    id="action-desc${rowIdx}-${ActionIdx}" name="action-desc${rowIdx}-${ActionIdx}"
                                    >no description
                                </p>
                            </td>`
                        ));

                        if( selectedScript == '---' )
                        {}
                        else {
                            $("#action" + rowIdx + "-" + ActionIdx)
                                .append(produceOptionsActionFilter(selectedScript, 'action'))
                                .val('---');
                        }

                        updateActionFiltersyntax( selectedScript, rowIdx, ActionIdx, FilterIdx);
                    }
                    else
                        $(this).append( $("<td></td>"));

                    testID++;
                });

                //not working
                var rows = $("#myTable").children('thead').children('tr');

                rows.each(function () {
                    $(this).append($(`<th class="text-center">
                        <button id="remove-action${ActionIdx}" class="btn btn-danger remove" type="button">Remove</button>
                        Action${ActionIdx}</th>`
                    ));
                });

                $('#remove-action'+ActionIdx).on('click', function() {
                    deleteColumn( deleteColumnID );
                });
            });

            $('#addFilterBtn').on('click', function() {

                var ActionIdx = columnActionIdx;
                var FilterIdx = ++columnFilterIdx;
                var deleteColumnID = ++columnIdx;

                var rows = $("#myTable").children('tbody').children('tr');
                //$("#myTable tr").append($("<td contenteditable='true'>FILTER</td>"));

                var selectedScript = $("#script"+rowIdx).children("option:selected").val();

                var testID = 1;
                rows.each(function () {

                    // Getting <tr> id.
                    var id = $(this).attr('id');
                    // Getting the <p> inside the .row-index class.
                    var Idx = $(this).children('.row-index').children('p');
                    // Gets the row number from <tr> id.
                    var dig = parseInt(id.substring(1));


                    if( testID == 1 )
                    {
                        $(this).append( $(
                            `<td id=${deleteColumnID} class="row-index text-center">
                                    <select name="filter${rowIdx}-${FilterIdx}" id="filter${rowIdx}-${FilterIdx}" style="width:100%">
                                    <option value="---" selected="selected">Select filter</option>
                                </select>
                                <select name="filter-operator${rowIdx}-${FilterIdx}" id="filter-operator${rowIdx}-${FilterIdx}" style="width:100%">
                                    <option value="---" selected="selected">Select operator</option>
                                </select>
                                <input type="text" disabled style="width:100%"
                                id="filter-input${rowIdx}-${FilterIdx}" name="filter-input${rowIdx}-${FilterIdx}"
                                    >
                                    </br>
                                    <p type="text" disabled style="width:100%"
                                id="filter-desc${rowIdx}-${FilterIdx}" name="filter-desc${rowIdx}-${FilterIdx}"
                                    >no description
                                </p>
                                <select name="filter-andor${rowIdx}-${FilterIdx}" id="filter-andor${rowIdx}-${FilterIdx}" style="width:100%">
                                    <option value="and" selected="selected">and</option>
                                    <option value="or">or</option>
                                </select>
                            </td>`
                        ));

                        if( selectedScript == '---' )
                        {}
                        else {
                            $("#filter" + rowIdx + "-" + FilterIdx)
                                .append(produceOptionsActionFilter(selectedScript, 'filter'))
                                .val('---');
                        }

                        updateActionFiltersyntax( selectedScript, rowIdx, ActionIdx, FilterIdx);
                    }
                    else
                        $(this).append( $("<td></td>"));

                    testID++;
                });


                //not working
                var rows = $("#myTable").children('thead').children('tr');
                rows.each(function () {
                    $(this).append($(`<th class="text-center">
                        <button id="remove-filter${FilterIdx}" class="btn btn-danger remove" type="button">Remove</button>
                        Filter${FilterIdx}</th>`
                    ));
                });


                $('#remove-filter'+FilterIdx).on('click', function() {
                    deleteColumn( deleteColumnID );
                });
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


                if (key.indexOf(",") !== -1 )
                {
                    var result=key.split(',');
                    $.each(result, function (key2, value)
                    {
                        var object = key2;
                        populated_options += "<option value='" + value + "'>" + value + "</option>";
                    });
                }
                else
                    populated_options += "<option value='"+key+"'>"+key+"</option>";

            });

            return populated_options;
        }

        function updateScriptsyntax( Idx ) {

            console.log( "actionID: "+columnActionIdx + "filterID: "+columnFilterIdx );

            var SCRIPT = $( "#script" + Idx ).children("option:selected").val();

            var tmpActiontext = "";
            var tmpActiontextapi = "";
            for( var i = 2; i <= columnActionIdx; i++ ) {
                var ACTION = $( "#action" + Idx+"-"+i ).children("option:selected").val();
                var ACTIONinput = $( "#action-input" + Idx+"-"+i ).val();


                if( ACTION !== "---" )
                {
                    if( ACTIONinput !== "" )
                        ACTIONinput = ":"+ACTIONinput;

                    if( i > 2 )
                    {
                        tmpActiontext += "/" ;
                        tmpActiontextapi += "/" ;
                    }

                    tmpActiontext += ACTION +ACTIONinput ;
                    tmpActiontextapi += ACTION +ACTIONinput ;
                }
            }
            var Actiontext = "";
            if( tmpActiontext !== "" )
                Actiontext = " 'actions=" +tmpActiontext+ "'" ;
            var Actiontextapi = "";
            if( tmpActiontextapi !== "" )
                Actiontextapi = "&actions=" +tmpActiontextapi;

            var tmpFiltertext = "";
            var tmpFiltertextapi = "";
            for( var i = 3; i <= columnFilterIdx; i++ ) {
                var FILTER = $("#filter" + Idx + "-" + i).children("option:selected").val();
                var FILTERoperator = $("#filter-operator" + Idx + "-" + i).children("option:selected").val();
                var FILTERinput = $("#filter-input" + Idx + "-" + i).val();

                var FILTERandor = $("#filter-andor" + Idx + "-" + i).children("option:selected").val();

                if (FILTER !== "---" && FILTERoperator !== "---") {

                    if( i > 3 )
                    {
                        tmpFiltertext += " "+FILTERandor+" " ;
                        tmpFiltertextapi += " "+FILTERandor+" " ;
                    }

                    tmpFiltertext += "(" + FILTER + " " + FILTERoperator + " " + FILTERinput + ")";
                    tmpFiltertextapi += "(" + FILTER + "%20" + FILTERoperator + "%20" + FILTERinput + ")";
                }
            }
            var Filtertext = "";
            if( tmpFiltertext !== "" )
                Filtertext = " 'filter=(  " + tmpFiltertext + "  )'";
            var Filtertextapi = "";
            if( tmpFiltertextapi !== "" )
                Filtertextapi = "&filter=( " + tmpFiltertextapi + " )";


            var message = "pa_" +SCRIPT+ "-edit";
            var message = "pan-os-php type=" +SCRIPT;
            message += Actiontext;
            message += Filtertext;


            //var checkedValue = document.getElementById('shadowjson').checked;
            var checkedValue = $( "#shadowjson" + Idx ).is(':checked');
            if( checkedValue )
                message += " shadow-json";
            else
                message += " shadow-nojson";

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

            //console.log( message ); //this is full CLI command
            $("#command" + Idx).val( message );


            var message2 = server_url + "/utils/develop/api/v1/tool.php/" +SCRIPT+ "?";
            message2 += Actiontextapi;
            message2 += Filtertextapi;

            if( checkedValue )
                message2 += "&shadow-json";
            else
                message2 += "&shadow-nojson";

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

            //console.log( message2 ); //this is full API command
            $("#commandapi" + Idx).val( message2 );

            //document.getElementById("user_form").action = message2;
            document.user_form.action = message2;
        }

        function updateActionFiltersyntax( selectedScript, Idx, ActionIdx, FilterIdx) {
            var selectedAction;
            var selectedFilter;

            $( "#action" + Idx+"-"+ActionIdx ).change(function(){
                selectedAction = $(this).children("option:selected").val();
                console.log( 'script:|'+selectedScript+'|');
                console.log( 'ACTION:|'+selectedAction+'|'); // this will show the info it in firebug console

                $("#action-desc" + Idx+"-"+ActionIdx).text( "no description");
                $("#action-input" + Idx+"-"+ActionIdx).prop( "disabled", true);

                if( selectedAction == '---' )
                {}
                else
                {
                    var action = subjectObject[selectedScript]['action'][selectedAction];

                    if( "args" in action )
                    {
                        var args = action['args'];
                        console.log( "ARGS: "+JSON.stringify( args ) );
                        $("#action-desc" + Idx+"-"+ActionIdx).text( JSON.stringify( args ) );


                        $("#action-input" + Idx+"-"+ActionIdx).prop( "disabled", false);

                    }

                }

                updateScriptsyntax( Idx );
            });

            $( "#action-input" + Idx+"-"+ActionIdx ).change(function(){
                updateScriptsyntax( Idx );
            });

            $("#filter" + Idx+"-"+FilterIdx).change(function(){
                selectedFilter = $(this).children("option:selected").val();
                console.log( 'FILTER:|'+selectedFilter+'|'); // this will show the info it in firebug console

                $("#filter-operator" + Idx+"-"+FilterIdx)
                    .find('option')
                    .remove()
                    .end()
                    .append( '<option value="---" selected="selected">Select operator</option>' );

                $("#filter-input" + Idx+"-"+FilterIdx).prop( "disabled", true)
                    .val( "");

                $("#filter-desc" + Idx+"-"+FilterIdx).text( "no description");

                if( selectedFilter == '---' )
                {}
                else
                {
                    $("#filter-operator" + Idx+"-"+FilterIdx)
                        .append(produceOptionsFilterOperator( selectedScript, selectedFilter))
                        .val('---');
                }

                updateScriptsyntax( Idx );
            });

            $("#filter-operator" + Idx+"-"+FilterIdx).change(function(){
                selectedFilterOperator = $(this).children("option:selected").val();
                console.log( 'FILTER-operator:|'+selectedFilterOperator+'|'); // this will show the info it in firebug console


                $("#filter-desc" + Idx+"-"+FilterIdx).text( "no description");

                if( selectedFilter == '---' )
                {}
                else
                {
                    check = ">,<,=,!"
                    if (check.indexOf(selectedFilterOperator) !== -1 )
                        selectedFilterOperator = check

                    var operator = subjectObject[selectedScript]['filter'][selectedFilter]['operators'][selectedFilterOperator];
                    var arg = operator['arg'];
                    console.log( "ARG: "+arg );

                    if( arg )
                    {
                        console.log( "ARG2: "+arg );
                        $("#filter-input" + Idx+"-"+FilterIdx).prop( "disabled", false);

                    }
                    else
                    {
                        $("#filter-input" + Idx+"-"+FilterIdx).prop( "disabled", true)
                            .val( "");
                    }

                    if( "help" in operator )
                    {
                        var help = operator['help'];
                        console.log( "HELP: "+help );
                        $("#filter-desc" + Idx+"-"+FilterIdx).text( help);
                    }
                }

                updateScriptsyntax( Idx );
            });

            $( "#filter-input" + Idx+"-"+FilterIdx ).change(function(){
                updateScriptsyntax( Idx );
            });

            $( "#filter-andor" + Idx+"-"+FilterIdx ).change(function(){
                updateScriptsyntax( Idx );
            });
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

        function copyTextButton( Idx) {

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

        function deleteColumn( column )
        {
            console.log( "delete column: "+column );
            if( column > 3 )
            {
                $("#myTable tr").find( "td:eq("+column+"),th:eq("+column+")" ).remove();
                columnIdx--;
            }
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
                            foreach( glob(dirname(__FILE__) . '/../api/v1/project/*') as $filename )
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

                        <button class="btn btn-md btn-primary"
                                id="addActionBtn" type="button">
                            new Action
                        </button>
                    </th>
                    <th class="text-center">
                        FILTER

                        <button class="btn btn-md btn-primary"
                                id="addFilterBtn" type="button">
                            new Filter
                        </button>
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

</body>

</html>