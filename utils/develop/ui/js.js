var server_url = window.location.protocol + "//" + window.location.host;
var fullpathname = window.location.pathname;
var pathToReplace = "/utils/develop/ui/";

var path = fullpathname.replace(pathToReplace, "");
path = path.replace("index.php", "");
path = path.replace("preparation.php", "");

server_url = server_url + path;

var subjectObject2 = subjectObject;

var rowIdx = 0;
var columnActionIdx = 1;
var columnFilterIdx = 0;
var columnIdx = 2;

$(document).ready(function () {

    createAddScript();

    $( "#json-store" ).submit(function( event ) {
        console.log( "done");
        console.log( $( "#json-store" ).serialize() );
    });


    // jQuery button click event to add a row
    $('#addBtn').on('click', function () {
        addNewRow();
    });


    // jQuery button click event to remove a row.
    $('#tbody').on('click', '.remove', function () {
        var Idx = $(this).closest('tr').attr('id');
        var IdxArray = Idx.split("-");
        Idx = IdxArray[0];
        Idx = Idx.replace("R", "");
        console.log( "delete rowID: "+Idx );

        $("#R" + Idx + "-1").closest('tr').remove();
        $("#R" + Idx + "-2").closest('tr').remove();
        $("#R" + Idx + "-3").closest('tr').remove();
        $("#R" + Idx + "-4").closest('tr').remove();
        $("#R" + Idx + "-5").closest('tr').remove();
    });



    $("#js-file").change(function(){
        var reader = new FileReader();
        reader.onload = function(e){
            createTableFromJSON(  e.target.result );
        };
        reader.readAsText($("#js-file")[0].files[0], "UTF-8");
    });

    $("#configSelect").change(function(){
        for (var i = 1; i <= rowIdx; i++) {
            updateScriptsyntax( i );
        }
    });

    // jQuery button click event create playbook JSON
    $('#storeBtn').on('click', function () {
        createJSONstringAndDownload();
    });


    taskAtStart();
});

