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



    $( "#json-store" ).submit(function( event ) {
        console.log( "done");
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
                        <select name="filter-andor${Idx}-${FilterIdx}" id="filter-andor${Idx}-${FilterIdx}" style="width:100%">
                                    <option value="" selected="selected">---</option>
                                    <option value="!">!</option>
                                </select>
                    </td>
                </tr>
                <tr id="R${Idx}">
                    <td>
                        shadow-json
                        <input type="checkbox" id="shadowjson${Idx}" name="shadowjson${Idx}"
                        >
                    </td>
                    <td>
                        location
                        <input type="text" id="location${Idx}" name="location${Idx}" value="" />
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




    $('#addActionBtn').on('click', function() {

        columnActionIdx = ++columnActionIdx;
        var ActionIdx = columnActionIdx;
        var FilterIdx = columnFilterIdx;
        columnIdx = ++columnIdx;
        var deleteColumnID = columnIdx;

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
        columnFilterIdx = ++columnFilterIdx;
        var FilterIdx = columnFilterIdx;
        columnIdx = ++columnIdx;
        var deleteColumnID = columnIdx;

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


            if( testID == 1 ) {
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
                                    <option value="and !" >and !</option>
                                    <option value="or !">or !</option>
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

    $("#js-file").change(function(){
        var reader = new FileReader();
        reader.onload = function(e){
            createTableFromJSON(  e.target.result );
        };
        reader.readAsText($("#js-file")[0].files[0], "UTF-8");
    });


    // jQuery button click event create playbook JSON
    $('#storeBtn').on('click', function () {

        console.log( rowIdx );

        var jsonSTRING = "";
        var jsonStringStart = "{\n";
        var jsonIN = "  \"in\": \"staging/ASA-Config-initial-10_0-fw.xml\",\n";
        var jsonOUT = "  \"out\": \"staging/final.xml\",\n";
        var jsonSTAGENAME = "  \"stagename\": \"staging/visibility-\",\n";
        var jsonHEADER = "  \"header-comment\": \"\",\n";
        var jsonFOOTER = "  \"footer-comment\": \"\",\n";
        var jsonCOMMANDstart = "  \"command\": [\n";

        var jsonCOMMAND1 = "    {\n" +
            "      \"type\": \"ironskillet-update\",\n" +
            "      \"comment\": \"\"\n" +
            "    }";
        var jsonCOMMAND2 = "    {\n" +
            "      \"type\": \"device\",\n" +
            "      \"actions\": \"actions=logforwardingprofile-create-bp\",\n" +
            "      \"comment\": \"\"\n" +
            "    }";

        var jsonCOMMANDend = "  ]\n";
        var jsonStringEnd = "}";

        jsonSTRING += jsonStringStart;
        //jsonSTRING += jsonIN;
        //jsonSTRING += jsonOUT;
        //jsonSTRING += jsonHEADER;
        //jsonSTRING += jsonFOOTER;
        jsonSTRING += jsonCOMMANDstart;

        var i = 1;
        for( i; i <= rowIdx; i++ )
        {
            var commandString = $( "#command" + i ).val();
            console.log( "command: " + commandString );
            console.log( "commandAPI: " + $( "#commandapi" + i ).val() );

            commandString = commandString.replace("pan-os-php ", "");
            commandString = commandString.replace(/ '/g, "|");
            commandString = commandString.replace(/' '/g, "|");
            commandString = commandString.replace(/' /g, "|");
            commandString = commandString.replace(/'/g, "");

            var text = "{ ";
            var res = commandString.split("|");
            let length = res.length;
            res.forEach( myFunction );


            function myFunction(item, index) {
                //item include string
                var entry = item.split("=");
                if (entry.hasOwnProperty( "1" ))
                {
                    if( entry[0] === "type" )
                        text += '"' + entry[0] + '":' + '"' + entry[1] + '"' ;
                    else
                        text += '"' + entry[0] + '":' + '"' + entry[0] + "=" + entry[1] + '"' ;
                }
                else
                    text += '"' + item + '":' + '"' + item + '"' ;

                text += ",";
            }
            //remove last , from string
            text = text.substring(0, text.length - 1);


            text += "},";
            jsonSTRING += text;
        }
        //remove last , from string
        jsonSTRING = jsonSTRING.substring(0, jsonSTRING.length - 1);

        jsonSTRING += jsonCOMMANDend;
        jsonSTRING += jsonStringEnd;

        var jsonPretty = JSON.stringify(JSON.parse(jsonSTRING),null,2);
        $("#json-display-out").val( jsonPretty );

        $("#json-display-out").height( "400px" );
        //setHeight($("#json-display-out"));

    });


    taskAtStart();
});

