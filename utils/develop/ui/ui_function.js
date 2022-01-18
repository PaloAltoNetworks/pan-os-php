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

            if( i >= 3 )
            {
                if( i ===3 )
                {
                    if (~FILTERandor.indexOf("!"))
                    {
                        tmpFiltertext += FILTERandor ;
                        tmpFiltertextapi += FILTERandor ;
                    }
                }
                else
                {
                    if (~FILTERandor.indexOf("!"))
                    {
                        tmpFiltertext += " " + FILTERandor ;
                        tmpFiltertextapi += "%20" + FILTERandor ;
                    }
                    else
                    {
                        tmpFiltertext += " "+FILTERandor+" " ;
                        tmpFiltertextapi += "%20"+FILTERandor+"%20" ;
                    }
                }
            }

            tmpFiltertext += "(" + FILTER + " " + FILTERoperator + " " + FILTERinput + ")";
            tmpFiltertextapi += "(" + FILTER + "%20" + FILTERoperator + "%20" + FILTERinput + ")";
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


    //var checkedValue = document.getElementById('shadowjson').checked;
    var checkedValue = $( "#shadowjson" + Idx ).is(':checked');
    if( checkedValue )
        message += " shadow-json";
    //else
    //    message += " shadow-nojson";

    //var locationValue = document.getElementById('location').value;
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
    //else
    //    message2 += "&shadow-nojson";

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

function ActionNewSet( Idx, ActionIdx, ACTION, ACTIONinput )
{
    $("#addActionBtn").trigger('click');
    ActionSet( Idx, ActionIdx, ACTION, ACTIONinput);
}

function FILTERNewSet( Idx, FilterIdx, FILTER, FILTERoperator, FILTERandor, FILTERinput )
{
    $("#addFilterBtn").trigger('click');
    FILTERSet( Idx, FilterIdx, FILTER, FILTERoperator, FILTERandor, FILTERinput);
}

function taskAtStart( )
{
    //add first row per default on loading the page
    $("#addBtn").trigger('click');


    //addPreFillRow( rowIdx );
}

function addPreFillRow( Idx )
{
    $("#addBtn").trigger('click');
    Idx = rowIdx;

    var ActionIdx = 2;
    var FilterIdx = 3;

    ScriptSet( Idx, "ironskillet-update");

    $("#addBtn").trigger('click');
    Idx = rowIdx;

    var ActionIdx = 2;
    var FilterIdx = 3;
    ScriptSet( Idx, "rule");
    ActionSet( Idx, ActionIdx, "display", "");
    FILTERSet( Idx, FilterIdx, "action", "is.allow", "", "");

    //ActionNewSet( Idx, ActionIdx+1, "delete", "");
    //FILTERNewSet( Idx, FilterIdx+1, "secprof", "type.is.profile", "and !", "");


    $("#addBtn").trigger('click');
    Idx = rowIdx;
    var ActionIdx = 2;
    var FilterIdx = 3;

    ScriptSet( Idx, "rule");
    ActionSet( Idx, ActionIdx, "delete", "");
    FILTERSet( Idx, FilterIdx, "secprof", "type.is.profile", "!", "");
}

function createTableFromJSON( textValue )
{
    //intermediate; display file value
    $("#js-textarea").val( textValue );
    //setHeight($("#js-textarea"));
    $("#js-textarea").height( '400px' );

    tableRemoveAll();

    rowIdx = 0;

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

            var result=result[1].split('/');
            //if result has now multiple settings, add newACION, missing

            for (var ii = 0; ii < result.length; ii++)
            {
                if( ii === 0 )
                {
                    result=result[ii].split(':');
                    var ACTION = result[0].toLowerCase();

                    if( ( 1 in result) )
                    {
                        var ACTIONinput = result[1];
                        ActionSet( Idx, ActionIdx, ACTION, ACTIONinput);
                    }
                    else
                        ActionSet( Idx, ActionIdx, ACTION, "");
                }
                else
                {
                    console.log( "ActionNewSet: " + result[ii] );
                }
            }
        }

        //----------------------------

        if( "filter" in command[i] )
        {
            var filter = command[i]['filter'];
            result=filter.split('=');



            var result=result[1].split(' and ');
            //if result has now multiple settings, add newACION, missing

            for (var ii = 0; ii < result.length; ii++)
            {
                if( ii === 0 )
                {
                    var andor = "";
                    if( result[ii].includes("!") )
                    {
                        andor = "!";
                        result[ii] = result[ii].replace( "!", "") ;
                    }

                    result = result[ii].replace( "(", "") ;
                    result = result.replace( ")", "") ;

                    result=result.split(' ');

                    if( 3 in result )
                        FILTERSet( Idx, FilterIdx, result[0], result[1], andor, result[3]);
                    else
                        FILTERSet( Idx, FilterIdx, result[0], result[1], andor, "");
                }
                else
                {

                }
            }

        }
    }
}