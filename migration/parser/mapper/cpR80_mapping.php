<?php







function cpr80_filecheck( $config_filename, &$someArray )
{
    global $expedition;
    global $mainfolder;
    global $newfolder;


    //validation if file has .tar.gz
    if( strpos($config_filename, ".tar.gz") === FALSE && strpos($config_filename, ".tgz") === FALSE )
    {
        derr("specified filename with argument 'FILE' is not 'tar.gz' ");
    }
    else
    {
        $srcfile = $config_filename;

        $destfile = $newfolder . '/'.uniqid().'.tar.gz';

        if( !copy($srcfile, $destfile) )
        {
            echo "File cannot be copied! \n";
        }
        else
        {
            #echo "File has been copied!\n";
        }

        //extract into specified folder
        exec('tar -C ' . $newfolder . '/' . ' -zxvf ' . $destfile . ' 2>&1');

        #print "sleep 15 seconds: wait for tar extract complete";
        #sleep(15);
    }

    $folder_path = $newfolder . "/";
    $config_path = "index.json";

    if( !file_exists($folder_path . $config_path) )
    {
        //print out all file / folder information
        $files10 = scandir($newfolder);
        unset($files10[0]);
        unset($files10[1]);

        if( !$expedition )
            print_r($files10);


        $folder_path = $newfolder . "/" . $files10[2] . "/";


        $files10 = scandir($folder_path);
        unset($files10[0]);
        unset($files10[1]);

        if( !$expedition )
            print_r($files10);

        foreach( $files10 as $tarFile )
        {
            exec('tar -C ' . $folder_path . '/' . ' -zxvf ' . $folder_path . "/" . $tarFile . ' 2>&1');
        }

        $files10 = scandir($folder_path);
        unset($files10[0]);
        unset($files10[1]);

        if( !$expedition )
            print_r($files10);

    }


#$someJSON = file($config_path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $someJSON = file_get_contents($folder_path . $config_path);


// Convert JSON string to Array
    $someArray = json_decode($someJSON, TRUE);
#print_r($someArray);        // Dump all data of the Array


    if( file_exists($newfolder) )
        delete_directory($newfolder);

}









