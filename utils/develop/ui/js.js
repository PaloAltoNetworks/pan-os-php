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
        createJSONstringAndDownload();
    });


    taskAtStart();
});

