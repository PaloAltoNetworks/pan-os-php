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

function addNewRow()
{
    rowIdx = ++rowIdx
    var Idx = rowIdx;
    var ActionIdx = columnActionIdx;
    var FilterIdx = columnFilterIdx;

    // Adding a row inside the tbody.
    $('#tbody').append(`<tr id="R${Idx}-1">
                        <td colspan="5">----------------------------------------------------------------------------------------------------</td>
                    </tr>
                    <tr id="R${Idx}-2">

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
                        <li>
                        allowmergingwithupperlevel
                        <input type="checkbox" id="allowmergingwithupperlevel${Idx}" name="allowmergingwithupperlevel${Idx}"
                        >
                        </li>
                        <li>
                        shadow-ignoreinvalidaddressobjects
                        <input type="checkbox" id="shadowignoreinvalidaddressobjects${Idx}" name="shadowignoreinvalidaddressobjects${Idx}" checked
                        >
                        </li>
                    </td>
                    <td>
                        <button id="add-action${Idx}-${ActionIdx}" class="btn btn-md btn-primary add-action${Idx}-${ActionIdx}" type="button">new Action</button>
                        <button id="add-filter${Idx}-${FilterIdx}" class="btn btn-md btn-primary add-filter${Idx}-${FilterIdx}" type="button">new Filter</button>
                    </td>
                </tr>
                <tr id="R${Idx}-3">
                    <td>
                        <input type="hidden" id="columnID-${Idx}" name="columnID-${Idx}" value="3" />
                        <br/>
                        <input type="hidden" id="actionID-${Idx}" name="actionID-${Idx}" value="1" />
                        <br/>
                        <input type="hidden" id="filterID-${Idx}" name="filterID-${Idx}" value="0" />
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
                <tr id="R${Idx}-4">
                    <td colspan="1"><button onclick="copyTextButton( ${Idx} )">Copy command</button></td>
                    <td colspan="4">
                        <input type="text" disabled style="width:100%"
                            id="command${Idx}" name="command${Idx}"
                        >
                    </td>

                </tr>
                <tr id="R${Idx}-5">
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

            var ActionIdx = $( "#actionID-" + Idx ).val();
            var FilterIdx = $( "#filterID-" + Idx ).val();

            for( var i = 1; i <= ActionIdx; i++ )
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

            for( var i = 1; i <= FilterIdx; i++ )
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


            updateScriptsyntax( Idx );

            if( selectedScript == '---' )
            {}
            else
            {
                for( var  i = 1; i <= ActionIdx; i++ )
                {
                    $( "#action" + Idx+"-"+i )
                        .append(produceOptionsActionFilter( selectedScript, 'action' ))
                        .val('---');

                    updateActionFiltersyntax( selectedScript, Idx, i, FilterIdx);
                }


                for( var i = 1; i <= FilterIdx; i++ )
                {
                    $( "#filter" + Idx+"-"+i )
                        .append(produceOptionsActionFilter( selectedScript, 'filter' ))
                        .val('---');

                    updateActionFiltersyntax( selectedScript, Idx, ActionIdx, i);
                }

            }



            updateActionFiltersyntax( selectedScript, Idx, ActionIdx, FilterIdx);
        });





    $("#shadowjson" + Idx ).change( function()
    {
        updateScriptsyntax( Idx );
    });

    $( "#location" + Idx ).change(function(){
        updateScriptsyntax( Idx );
    });

    $("#allowmergingwithupperlevel" + Idx ).change( function()
    {
        updateScriptsyntax( Idx );
    });

    $("#shadowignoreinvalidaddressobjects" + Idx ).change( function()
    {
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
}

function updateScriptsyntax( Idx ) {

    var ActionIdx = $( "#actionID-" + Idx ).val();
    var FilterIdx = $( "#filterID-" + Idx ).val();


    console.log( "actionID: "+ActionIdx + "| filterID: "+FilterIdx );

    var SCRIPT = $( "#script" + Idx ).children("option:selected").val();

    var tmpActiontext = "";
    var tmpActiontextapi = "";


    for( var i = 1; i <= ActionIdx; i++ )
    {
        console.log( "actionID-update: "+Idx+"-"+i);

        if ( $( "#action" + Idx+"-"+i ).children("option:selected").val() === undefined)
            continue;

        var ACTION = $( "#action" + Idx+"-"+i ).children("option:selected").val();
        var ACTIONinput = $( "#action-input" + Idx+"-"+i ).val();


        if( ACTION !== "---" )
        {
            if( ACTIONinput !== "" )
                ACTIONinput = ":"+ACTIONinput;

            if( i > 1 )
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



    for( var i = 1; i <= FilterIdx; i++ )
    {
        console.log( "filterID-update: "+Idx+"-"+i);
        if ( $("#filter" + Idx + "-" + i).children("option:selected").val() === undefined)
            continue;

        var FILTER = $("#filter" + Idx + "-" + i).children("option:selected").val();
        var FILTERoperator = $("#filter-operator" + Idx + "-" + i).children("option:selected").val();
        var FILTERinput = $("#filter-input" + Idx + "-" + i).val();

        var FILTERandor = $("#filter-andor" + Idx + "-" + i).children("option:selected").val();

        if ( FILTER !== "---" && FILTERoperator !== "---") {

            if ( typeof FILTERandor === 'string' || FILTERandor instanceof String)
            {
                if( i === 1 )
                {
                    if (~FILTERandor.indexOf("!"))
                    {
                        tmpFiltertext += FILTERandor ;
                        tmpFiltertextapi += FILTERandor.replace( " ", "%20" ) ;
                    }
                }
                else if( i > 1 )
                {
                    if (~FILTERandor.indexOf("!"))
                    {
                        tmpFiltertext += " " + FILTERandor ;
                        tmpFiltertextapi += "%20" + FILTERandor.replace( " ", "%20" ) ;
                    }
                    else
                    {
                        tmpFiltertext += " "+FILTERandor+" " ;
                        tmpFiltertextapi += "%20"+FILTERandor+"%20" ;
                    }
                }

                tmpFiltertext += "(" + FILTER + " " + FILTERoperator + " " + FILTERinput + ")";
                tmpFiltertextapi += "(" + FILTER + "%20" + FILTERoperator + "%20" + FILTERinput + ")";
            }
        }
    }
    var Filtertext = "";
    if( tmpFiltertext !== "" )
        Filtertext = " 'filter=" + tmpFiltertext + "'";
    var Filtertextapi = "";
    if( tmpFiltertextapi !== "" )
        Filtertextapi = "&filter=" + tmpFiltertextapi + "";


    var message = "pa_" +SCRIPT+ "-edit";
    var message = "pan-os-php type=" +SCRIPT;
    message += Actiontext;
    message += Filtertext;


    var checkedValue = $( "#shadowjson" + Idx ).is(':checked');
    if( checkedValue )
        message += " 'shadow-json'";

    var locationValue = $( "#location" + Idx ).val();
    if( locationValue !== "---" && locationValue !== "" )
    {
        message += " 'location=";
        message += locationValue;
        message += "'";
    }

    var allowmergingcheckedValue = $( "#allowmergingwithupperlevel" + Idx ).is(':checked');
    if( allowmergingcheckedValue )
        message += " 'allowmergingwithupperlevel'";

    var offlinemode = $( "#offlinemode" ).is(':checked');
    if( offlinemode )
    {
        var e = document.getElementById("configSelect");
        var dropdownselection = e.options[e.selectedIndex].text;
        console.log( "DropDown: "+dropdownselection );

        if( dropdownselection !== "---" )
        {
            message += " 'in=";
            message += dropdownselection;
            message += "'";
        }
    }

    var onlinemode = $( "#onlinemode" ).is(':checked');
    if( onlinemode )
    {
        var configapi = $( "#configapi" ).val();

        message += " 'in=api://";
        message += configapi;
        message += "'";
    }


    message += " 'shadow-ignoreinvalidaddressobjects'";

    //console.log( message ); //this is full CLI command
    $("#command" + Idx).val( message );


    var message2 = server_url + "/utils/api/v1/tool.php/" +SCRIPT+ "?";
    message2 += Actiontextapi;
    message2 += Filtertextapi;

    if( checkedValue )
        message2 += "&shadow-json";
    else
        message2 += "&shadow-nojson";

    if( locationValue !== "---" && locationValue !== "" )
    {
        message2 += "&location=";
        message2 += locationValue;
    }

    if( allowmergingcheckedValue )
        message2 += "&allowmergingwithupperlevel";


    if( offlinemode )
    {
        if( dropdownselection !== "---" )
        {
            message2 += "&in=";
            message2 += dropdownselection;
        }
    }

    if( onlinemode )
    {
        message2 += "&in=api://";
        message2 += configapi;
    }

    message2 += "&shadow-ignoreinvalidaddressobjects";

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

                var string = "";
                for( var i=0; i <= args.length; i++)
                {
                    console.log( "ARGS1: "+args[i] );
                    string += JSON.stringify( args[i] ) + "<br/>";
                }


                $("#action-desc" + Idx+"-"+ActionIdx).text( JSON.stringify( args ) );
                //$("#action-desc" + Idx+"-"+ActionIdx).text( string );

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




    /* Copy the text inside the text field */
    navigator.clipboard.writeText(string);

    /* Alert the copied text */
    alert("Copied the text: " + string);
}

function runButton( Idx)
{
    //document.getElementById("user_form").submit();
}

function uploadButton( )
{
    var message = server_url + "/utils/api/v1/file_upload.php"
    document.getElementById("user_form").action = message;
    document.getElementById("user_form").submit();
}



function deleteColumn( column, Idx )
{
    console.log( "delete column: "+column );
    if( column > 2 )
    {
        $( "#R"+Idx+"column"+column+"-1").remove();
        $( "#R"+Idx+"column"+column+"-2").remove();
    }

    updateScriptsyntax( Idx );
}


function tableRemoveAll()
{
    $('#tbody').empty();
}

function setHeight(jq_in){
    jq_in.each(function(index, elem){
        elem.style.height = elem.scrollHeight+'px';
    });
}

function eraseText() {
    $("#js-textarea").val("");
    $("#js-textarea").height( '40px' );
}

function ScriptSet( Idx, SCRIPTtype )
{
    $("#script" + Idx ).find('option[value="'+ SCRIPTtype +'"]').attr('selected','selected');
    $("#script" + Idx ).change();
}

function ActionSet( Idx, ActionIdx, ACTION, ACTIONinput )
{
    $( "#action" + Idx+"-"+ActionIdx ).find('option[value="'+ ACTION +'"]').attr('selected','selected');
    $( "#action" + Idx+"-"+ActionIdx ).change();

    if( ACTIONinput !== "" )
    {
        $( "#action-input" + Idx+"-"+ActionIdx ).val( ACTIONinput );
        $( "#action-input" + Idx+"-"+ActionIdx ).change();
    }
}

function shadowjsonSet( Idx )
{
    $( "#shadowjson" + Idx ).attr("checked", true);
    $( "#shadowjson" + Idx ).change();
}

function locationSet( Idx, locationValue )
{
    $( "#location" + Idx ).val( locationValue );
    $( "#location" + Idx ).change();
}

function allowmergingwithupperlevelSet( Idx )
{
    $( "#allowmergingwithupperlevel" + Idx ).attr("checked", true);
    $( "#allowmergingwithupperlevel" + Idx ).change();
}

function shadowignoreinvalidaddressobjects( Idx )
{
    $( "#shadowignoreinvalidaddressobjects" + Idx ).attr("checked", true);
    $( "#shadowignoreinvalidaddressobjects" + Idx ).change();
}


function FILTERSet( Idx, FilterIdx, FILTER, FILTERoperator, FILTERandor, FILTERinput )
{
    $("#filter" + Idx+"-"+FilterIdx ).find('option[value="'+ FILTER +'"]').attr('selected','selected');
    $("#filter" + Idx+"-"+FilterIdx ).change();

    $("#filter-operator" + Idx+"-"+FilterIdx ).find('option[value="'+ FILTERoperator +'"]').attr('selected','selected');
    $("#filter-operator" + Idx+"-"+FilterIdx ).change();

    if( FILTERinput !== "" ) {
        $("#filter-input" + Idx+"-"+FilterIdx ).val( FILTERinput );
        $("#filter-input" + Idx+"-"+FilterIdx ).change();
    }

    if( FILTERandor !== "" ) {
        $("#filter-andor" + Idx + "-" + FilterIdx).find('option[value="' + FILTERandor + '"]').attr('selected', 'selected');
        $("#filter-andor" + Idx + "-" + FilterIdx).change();
    }
}

function ActionNewSet( Idx, ACTION, ACTIONinput )
{
    $("#add-action"+Idx+"-"+"1").trigger('click');

    var ActionIdx = $( "#actionID-" + Idx ).val();
    ActionSet( Idx, ActionIdx, ACTION, ACTIONinput);
}

function FILTERNewSet( Idx, FILTER, FILTERoperator, FILTERandor, FILTERinput )
{
    $("#add-filter"+Idx+"-"+"0").trigger('click');

    var FilterIdx = $( "#filterID-" + Idx ).val();
    FILTERSet( Idx, FilterIdx, FILTER, FILTERoperator, FILTERandor, FILTERinput);
}


function createTableFromJSON( textValue )
{
    //intermediate; display file value
    $("#js-textarea").val( textValue );
    //setHeight($("#js-textarea"));
    $("#js-textarea").height( '400px' );

    tableRemoveAll();
    //missing stuff, check that all additional columns actions / filters are also removed

    for (var i = 1; i <= rowIdx; i++) {
        for (var ii = 3; ii <= columnIdx; ii++) {
            deleteColumn(ii, i);
        }
    }

    rowIdx = 0;
    columnActionIdx = 1;
    columnFilterIdx = 0;
    columnIdx = 3;

    const obj = JSON.parse( textValue );
    var command = obj.command;

    for (var i = 0; i < command.length; i++)
    {

        var type = command[i]['type'];


        $("#addBtn").trigger('click');

        var Idx = rowIdx;
        var ActionIdx = 1;
        var FilterIdx = 0;

        ScriptSet( Idx, type);

        //----------------------------

        if( "actions" in command[i] )
        {
            var actions = command[i]['actions'];
            var result=actions.split('=');
            result=result[1].split('/');

            for (var ii = 0; ii < result.length; ii++)
            {
                string=result[ii].split(':');
                var ACTION = string[0].toLowerCase();
                var ACTIONinput = "";
                if( ( 1 in string) )
                    ACTIONinput = string[1];

                if( ii === 0 )
                    ActionSet( Idx, ActionIdx, ACTION, ACTIONinput);
                else
                    ActionNewSet( Idx, ACTION, ACTIONinput);
            }
        }

        //----------------------------

        if( "filter" in command[i] )
        {
            var filter = command[i]['filter'];
            result=filter.split('=');
            result=result[1].split(') ');

            for (var ii = 0; ii < result.length; ii++)
            {
                var andor = "";
                var string = result[ii];

                var replace = [];
                if( ii === 0 )
                    replace = ["!"];
                else
                    replace = ["and !", "or !", "and ", "or "];

                for( var k=0; k < replace.length; k++ )
                {
                    if( string.includes( replace[k] ) )
                    {
                        andor = replace[k];
                        string = string.replace( replace[k], "") ;
                    }
                }

                string = string.replace( "(", "") ;
                string = string.replace( ")", "") ;
                string = string.replace( "(", "") ;

                string=string.split(' ');

                var FilterInput = "";
                if( 2 in string )
                    FilterInput = string[2];

                //if( ii === 0 )
                //    FILTERSet( Idx, FilterIdx, string[0], string[1], andor, FilterInput);
                //else
                    FILTERNewSet( Idx, string[0], string[1], andor, FilterInput);
            }

        }

        //missing part; load shadow-json / allowmergingwithupperlevel / location aso.
        if( "location" in command[i] )
        {
            var locationValue = command[i]['location'];
            locationSet(Idx, locationValue)
        }
        if( "shadow-json" in command[i] )
        {
            shadowjsonSet(Idx);
        }
        if( "allowmergingwithupperlevel" in command[i] )
        {
            allowmergingwithupperlevelSet(Idx)
        }
        if( "shadowignoreinvalidaddressobjects" in command[i] )
        {
            shadowignoreinvalidaddressobjects(Idx)
        }

    }
}


function addActionBtn( Idx )
{
    var ActionIdx = $( "#actionID-" + Idx ).val();
    var FilterIdx = $( "#filterID-" + Idx ).val();
    var columnIdx = $( "#columnID-" + Idx ).val();

    ActionIdx = ++ActionIdx;
    columnIdx = ++columnIdx;

    console.log( "addAction: ROW:"+Idx+ "-"+ActionIdx);

    //update
    $("#actionID-" + Idx).val( ActionIdx );
    $("#columnID-" + Idx).val( columnIdx );


    var selectedScript = $("#script"+rowIdx).children("option:selected").val();


    $( "#R"+Idx+"-2" ).append( $(`<td id="R${Idx}column${columnIdx}-1"><button id="remove-action${Idx}-${columnIdx}" class="btn btn-danger remove-action${Idx}-${columnIdx}" type="button">delete Action${ActionIdx}</button></td>`));
    $( "#R"+Idx+"-3" ).append( $(
        `<td id="R${Idx}column${columnIdx}-2" class="row-index text-center">
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
                    </td>`
    ));

    if( selectedScript == '---' )
    {}
    else {
        $("#action" + Idx + "-" + ActionIdx)
            .append(produceOptionsActionFilter(selectedScript, 'action'))
            .val('---');
    }

    updateActionFiltersyntax( selectedScript, Idx, ActionIdx, FilterIdx);


    $('#remove-action'+Idx+'-'+columnIdx).on('click', function() {
        deleteColumn( columnIdx, Idx );
    });
}

function addFilterBtn( Idx)
{
    var ActionIdx = $( "#actionID-" + Idx ).val();
    var FilterIdx = $( "#filterID-" + Idx ).val();
    var columnIdx = $( "#columnID-" + Idx ).val();

    FilterIdx = ++FilterIdx;
    columnIdx = ++columnIdx;

    console.log( "addFilter: ROW:"+Idx+ "-"+FilterIdx);

    //update
    $("#filterID-" + Idx).val( FilterIdx );
    $("#columnID-" + Idx).val( columnIdx );


    var selectedScript = $("#script"+Idx).children("option:selected").val();


    if( FilterIdx === 1 )
    {
        string = `<td id="R${Idx}column${columnIdx}-1">`;
        string += `<select name="filter-andor${Idx}-${FilterIdx}" id="filter-andor${Idx}-${FilterIdx}" style="width:100%">\n` +
            `                                    <option value="" selected="selected">---</option>\n` +
            `                                    <option value="!">!</option>\n` +
            `                                </select>`;
    }
    else
    {
        string = `<td id="R${Idx}column${columnIdx}-1"><button id="remove-filter${Idx}-${columnIdx}" class="btn btn-danger remove-filter${Idx}-${columnIdx}" type="button">delete Filter${FilterIdx}</button>`;
        string += `<select name="filter-andor${Idx}-${FilterIdx}" id="filter-andor${Idx}-${FilterIdx}" style="width:100%">\n` +
            `                                    <option value="and" selected="selected">and</option>\n` +
            `                                    <option value="or">or</option>\n` +
            `                                    <option value="and !" >and !</option>\n` +
            `                                    <option value="or !">or !</option>\n` +
            `                                </select>`;
    }


    string += "</td>";

    $( "#R"+Idx+"-2" ).append( $( string ));


    $( "#R"+Idx+"-3" ).append( $(
        `<td id="R${Idx}column${columnIdx}-2" class="row-index text-center">
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
                    </td>`
    ));

    if( selectedScript == '---' )
    {}
    else {
        $("#filter" + Idx + "-" + FilterIdx)
            .append(produceOptionsActionFilter(selectedScript, 'filter'))
            .val('---');
    }

    updateActionFiltersyntax( selectedScript, Idx, ActionIdx, FilterIdx);



    $('#remove-filter' + Idx + '-' + columnIdx).on('click', function() {
        deleteColumn( columnIdx, Idx );
    });
}

function download(filename, text) {
    var element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', filename);

    element.style.display = 'none';
    document.body.appendChild(element);

    element.click();

    document.body.removeChild(element);
}

function createJSONstringAndDownload()
{
    console.log( rowIdx );

    var jsonSTRING = "";
    var jsonStringStart = "{\n";
    var jsonIN = "  \"in\": \"staging/ASA-Config-initial-10_0-fw.xml\",\n";
    var jsonOUT = "  \"out\": \"staging/final.xml\",\n";
    var jsonSTAGENAME = "  \"stagename\": \"staging/visibility-\",\n";
    var jsonHEADER = "  \"header-comment\": \"\",\n";
    var jsonFOOTER = "  \"footer-comment\": \"\",\n";
    var jsonCOMMANDstart = "  \"command\": [\n";


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
        if ( $( "#command" + i ).val() === undefined)
            continue;

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


    var filename = $("#json-output").val();
    // Start file download.
    download(filename,jsonPretty);
}

function taskAtStart( )
{
    //add first row per default on loading the page
    $("#addBtn").trigger('click');

    //addPreFillRow( );
}

function addPreFillRow( )
{
    ////////////////////////////////////////////////////////////////////////
    //FIRST ROW
    //$("#addBtn").trigger('click');
    //var Idx = rowIdx;
    //var ActionIdx = $( "#actionID-" + Idx ).val();
    //var FilterIdx = $( "#filterID-" + Idx ).val();

    //ScriptSet( Idx, "ironskillet-update");



    ////////////////////////////////////////////////////////////////////////
    //SECOND ROW
    $("#addBtn").trigger('click');
    var Idx = rowIdx;
    var ActionIdx = $( "#actionID-" + Idx ).val();
    var FilterIdx = $( "#filterID-" + Idx ).val();

    ScriptSet( Idx, "rule");
    ActionSet( Idx, ActionIdx,"display", "");
    ActionNewSet( Idx, "delete", "");

    FILTERNewSet( Idx,"secprof", "type.is.profile", "", "");
    FILTERNewSet( Idx,"secprof", "vuln-profile.is.set", "", "");
    FILTERNewSet( Idx,"action", "is.allow", "", "");
    FILTERNewSet( Idx,"rule", "is.disabled", "", "");


    ////////////////////////////////////////////////////////////////////////
    //THIRD ROW
    $("#addBtn").trigger('click');
    var Idx = rowIdx;
    var ActionIdx = $( "#actionID-" + Idx ).val();
    var FilterIdx = $( "#filterID-" + Idx ).val();

    ScriptSet( Idx, "ironskillet-update");


    ////////////////////////////////////////////////////////////////////////
    /*
    $("#addBtn").trigger('click');
    Idx = ++Idx;
    var ActionIdx = 1;
    var FilterIdx = 0;

    ScriptSet( Idx, "rule");
    ActionSet( Idx, ActionIdx, "delete", "");
    FILTERSet( Idx, FilterIdx, "secprof", "type.is.profile", "!", "");
    */

}
