var server_url = window.location.protocol + "//" + window.location.host;
var fullpathname = window.location.pathname;
var pathToReplace = "/utils/develop/ui/";

var path = fullpathname.replace(pathToReplace, "");
server_url = server_url + path;

var subjectObject2 = subjectObject;

var rowIdx = 0;
var columnActionIdx = 1;
var columnFilterIdx = 0;
var columnIdx = 2;

$(document).ready(function () {

    // Denotes total number of rows



    $( "#json-store" ).submit(function( event ) {
        console.log( "done");
        console.log( $( "#json-store" ).serialize() );
    });

    // jQuery button click event to add a row
    $('#addBtn').on('click', function () {

        rowIdx = ++rowIdx
        var Idx = rowIdx;
        var ActionIdx = columnActionIdx;
        var FilterIdx = columnFilterIdx;

        // Adding a row inside the tbody.
        $('#tbody').append(`<tr id="R${Idx}">

                    <td class="text-center">
                        <button class="btn btn-danger remove"
                        type="button">Remove</button>
                    </td>
                    <td>
                        <li>
                        shadow-json
                        <input type="checkbox" id="shadowjson${Idx}" name="shadowjson${Idx}"
                        >
                        </li><li>
                        location
                        <input type="text" id="location${Idx}" name="location${Idx}" value="" />
                        </li>
                    </td>
                    <td>
                        <button id="add-action${Idx}-${ActionIdx}" class="btn btn-md btn-primary add-action${Idx}-${ActionIdx}" type="button">new Action2</button>
                        <button id="add-filter${Idx}-${FilterIdx}" class="btn btn-md btn-primary add-filter${Idx}-${FilterIdx}" type="button">new Filter2</button>
                    </td>
                </tr>
                <tr id="R${Idx}">
                    <td>
                        <input type="text" id="columnID-${Idx}" name="columnID-${Idx}" value="3" />
                        <br/>
                        <input type="text" id="actionID-${Idx}" name="actionID-${Idx}" value="1" />
                        <br/>
                        <input type="text" id="filterID-${Idx}" name="filterID-${Idx}" value="0" />
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
                        <p type="text" disabled style="width:100%"
                            id="action-desc${Idx}-${ActionIdx}" name="action-desc${Idx}-${ActionIdx}"
                        >no description
                        </p>
                    </td>
                </tr>
                <tr id="R${Idx}">
                    <td colspan="1"><button onclick="copyTextButton( ${Idx} )">Copy command</button></td>
                    <td colspan="4">
                        <input type="text" disabled style="width:100%"
                            id="command${Idx}" name="command${Idx}"
                        >
                    </td>

                </tr>
                <tr id="R${Idx}">
                    <td colspan="1">
                        <button onclick="runButton( ${Idx} )">RUN single command</button>
                    </td>
                    <td colspan="4">
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


                for( var i = 1; i <= columnActionIdx; i++ )
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

                for( var i = 1; i <= columnFilterIdx; i++ )
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
                    for( var  i = 1; i <= columnActionIdx; i++ )
                        $( "#action" + Idx+"-"+i )
                            .append(produceOptionsActionFilter( selectedScript, 'action' ))
                            .val('---');

                    for( var i = 1; i <= columnFilterIdx; i++ )
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


        $('#add-action' + Idx + '-' + ActionIdx).on('click', function() {
            console.log("TEST1");
            addActionBtn( Idx );
        });

        $('#add-filter' + Idx + '-' + FilterIdx).on('click', function() {
            console.log("TEST2");
            addFilterBtn( Idx );
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

