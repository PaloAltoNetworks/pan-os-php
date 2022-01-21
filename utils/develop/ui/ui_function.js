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

        if ( FILTER !== "---" && FILTERoperator !== "---") {

            if ( typeof FILTERandor === 'string' || FILTERandor instanceof String)
            {
                if( i === 3 )
                {
                    if (~FILTERandor.indexOf("!"))
                    {
                        tmpFiltertext += FILTERandor ;
                        tmpFiltertextapi += FILTERandor.replace( " ", "%20" ) ;
                    }
                }
                else if( i > 3 )
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
        message += " shadow-json";

    var locationValue = $( "#location" + Idx ).val();
    if( locationValue !== "---" && locationValue !== "" )
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

    if( locationValue !== "---" && locationValue !== "" )
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
    if( column > 2 )
    {
        $("#myTable tr").find( "td:eq("+column+"),th:eq("+column+")" ).remove();
        columnIdx--;
    }
}

function deleteColumnIdx( Idx, column )
{
    console.log( "delete column: "+column );
    if( column > 2 )
    {
        $("#myTable tr").find( "td:eq("+column+"),th:eq("+column+")" ).remove();
        columnIdx--;
    }
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
    $("#addActionBtn").trigger('click');
    ActionIdx = columnActionIdx;
    ActionSet( Idx, ActionIdx, ACTION, ACTIONinput);
}

function FILTERNewSet( Idx, FILTER, FILTERoperator, FILTERandor, FILTERinput )
{
    $("#addFilterBtn").trigger('click');
    FilterIdx = columnFilterIdx;

    FILTERSet( Idx, FilterIdx, FILTER, FILTERoperator, FILTERandor, FILTERinput);
}

function taskAtStart( )
{
    //add first row per default on loading the page
    $("#addBtn").trigger('click');


    //addPreFillRow( );
}

function addPreFillRow( )
{
    /*
    $("#addBtn").trigger('click');
    Idx = rowIdx;

    var ActionIdx = 2;
    var FilterIdx = 3;

    ScriptSet( Idx, "ironskillet-update");

    */
    $("#addBtn").trigger('click');
    Idx = rowIdx;

    var ActionIdx = 2;
    var FilterIdx = 3;

    ScriptSet( Idx, "rule");
    ActionSet( Idx, ActionIdx,"display", "");
    FILTERSet( Idx, FilterIdx,"secprof", "type.is.profile", "", "");

    //ActionNewSet( Idx, ActionIdx+1, "delete", "");

    FILTERNewSet( Idx,"secprof", "vuln-profile.is.set", "", "");
    FILTERNewSet( Idx,"action", "is.allow", "", "");
    FILTERNewSet( Idx,"rule", "is.disabled", "", "");


    /*
    $("#addBtn").trigger('click');
    Idx = rowIdx;
    var ActionIdx = 2;
    var FilterIdx = 3;

    ScriptSet( Idx, "rule");
    ActionSet( Idx, ActionIdx, "delete", "");
    FILTERSet( Idx, FilterIdx, "secprof", "type.is.profile", "!", "");
     */
}

function createTableFromJSON( textValue )
{
    //intermediate; display file value
    $("#js-textarea").val( textValue );
    //setHeight($("#js-textarea"));
    $("#js-textarea").height( '400px' );

    tableRemoveAll();
    //missing stuff, check that all additional columns actions / filters are also removed

    for (var i = 4; i <= columnIdx; i++) {
        deleteColumn( i );
    }

    rowIdx = 0;
    columnActionIdx = 2;
    columnFilterIdx = 3;
    columnIdx = 3;

    const obj = JSON.parse( textValue );
    var command = obj.command;

    for (var i = 0; i < command.length; i++) {

        //"type": "rule",
        //    "actions": "actions=securityProfile-Profile-Set:vulnerability,Alert-Only-VP",
        //    "filter": "filter=(secprof type.is.profile) and !(secprof vuln-profile.is.set) and (action is.allow) and !(rule is.disabled)"

        //----------------------------

        var type = command[i]['type'];


        $("#addBtn").trigger('click');

        var Idx = rowIdx;
        var ActionIdx = 2;
        var FilterIdx = 3;

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

                if( ii === 0 )
                    FILTERSet( Idx, FilterIdx, string[0], string[1], andor, FilterInput);
                else
                    FILTERNewSet( Idx, string[0], string[1], andor, FilterInput);
            }

        }
    }
}

function ActionAddRow( rIdx, ActionIdx, FilterIdx )
{

    var selectedScript = $("#script"+rIdx).children("option:selected").val();


    for( var k=1; k <= 4; k++ )
    {
        if( k === 1 )
        {
            $(this).append( $(
                `<td id=${deleteColumnID} class="row-index text-center">
                                <select name="action${rIdx}-${ActionIdx}" id="action${rIdx}-${ActionIdx}" style="width:100%">
                                    <option value="---" selected="selected">Select action</option>
                                </select>
                                <input type="text" disabled style="width:100%"
                                    id="action-input${rIdx}-${ActionIdx}" name="action-input${rIdx}-${ActionIdx}"
                                    >
                                </br>
                                <p type="text" disabled style="width:100%"
                                    id="action-desc${rIdx}-${ActionIdx}" name="action-desc${rIdx}-${ActionIdx}"
                                    >no description
                                </p>
                            </td>`
            ));

            if( selectedScript === '---' )
            {}
            else {
                $("#action" + rIdx + "-" + ActionIdx)
                    .append(produceOptionsActionFilter(selectedScript, 'action'))
                    .val('---');
            }

            updateActionFiltersyntax( selectedScript, rIdx, ActionIdx, FilterIdx);
        }
        else if( k === 2 )
        {
            $(this).append( $("<td><button id=\"remove-action2BTN\" class=\"btn btn-danger remove-action2\" type=\"button\">RemoveA2</button></td>"));
        }
        else
            $(this).append( $("<td></td>"));
    }


}

function addActionBtn()
{
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

        if( testID === 1 )
        {
            $(this).append( $("<td><button id=\"remove-action2BTN\" class=\"btn btn-danger remove-action2\" type=\"button\">RemoveA2</button></td>"));
        }
        else if( testID === 2 )
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
}

function addFilterBtn()
{
    var ActionIdx = columnActionIdx;

    if( columnFilterIdx > 3 )
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


        if( testID === 1 )
        {
            string = "<td><button id=\"remove-filter2BTN\" class=\"btn btn-danger remove-filter2\" type=\"button\">RemoveF2</button>";

            if( FilterIdx === 3 )
                string += "<select name=\"filter-andor${Idx}-${FilterIdx}\" id=\"filter-andor${Idx}-${FilterIdx}\" style=\"width:100%\">\n" +
                    "                                    <option value=\"\" selected=\"selected\">---</option>\n" +
                    "                                    <option value=\"!\">!</option>\n" +
                    "                                </select>";
            else
                string += "<select name=\"filter-andor${rowIdx}-${FilterIdx}\" id=\"filter-andor${rowIdx}-${FilterIdx}\" style=\"width:100%\">\n" +
                    "                                    <option value=\"and\" selected=\"selected\">and</option>\n" +
                    "                                    <option value=\"or\">or</option>\n" +
                    "                                    <option value=\"and !\" >and !</option>\n" +
                    "                                    <option value=\"or !\">or !</option>\n" +
                    "                                </select>";

            string += "</td>";

            $(this).append( $( string ));
        }
        else if( testID === 2 ) {
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

    if( columnFilterIdx === 3 )
        columnFilterIdx = ++columnFilterIdx;
}